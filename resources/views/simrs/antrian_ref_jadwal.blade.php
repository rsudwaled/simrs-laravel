@extends('adminlte::page')

@section('title', 'Referensi Jadwal Dokter')

@section('content_header')
    <h1>Referensi Jadwal Dokter</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <x-adminlte-card title="Data Informasi Jadwal Dokter" theme="info" icon="fas fa-info-circle" collapsible
                maximizable>
                @php
                    $heads = ['Nama Poliklinik', 'Kode Poli', 'Dokter', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu'];
                @endphp
                <x-adminlte-datatable id="table1" class="nowrap" :heads="$heads" striped bordered hoverable compressed>
                    @foreach ($jadwals->groupby('namadokter') as $item)
                        <tr>
                            <td>{{ $item->first()->namasubspesialis }}</td>
                            <td>{{ $item->first()->kodesubspesialis }}</td>
                            <td>{{ $item->first()->namadokter }}</td>
                            @for ($i = 1; $i <= 6; $i++)
                                <td>
                                    @foreach ($item as $jadwal)
                                        @if ($jadwal->hari == $i)
                                            <x-adminlte-button
                                                label="{{ \Carbon\Carbon::parse($jadwal->jadwal)->format('H:i') }}-{{ \Carbon\Carbon::parse($jadwal->jam_selesai)->format('H:i') }}"
                                                class="btn-xs mb-1" theme="warning" data-toggle="tooltip"
                                                title="{{ $jadwal->namadokter }}" onclick="window.location='#'" />
                                        @endif
                                    @endforeach
                                </td>
                            @endfor
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
                <a href="{{ route('antrian.ref.get_poli_bpjs') }}" class="btn btn-success">Refresh</a>
            </x-adminlte-card>
            <x-adminlte-card title="Informasi Referensi Jadwal Dokter" theme="info" icon="fas fa-info-circle" collapsible
                maximizable>
                <form action="{{ route('antrian.ref.get_jadwal_bpjs') }}" method="get">
                    @php
                        $config = ['format' => 'YYYY-MM-DD'];
                    @endphp
                    <x-adminlte-input-date name="tanggalperiksa" value="{{ Carbon\Carbon::now()->format('Y-m-d') }}"
                        label="Tanggal Periksa" :config="$config" />
                    <x-adminlte-select2 name="kodepoli" id="kodepoli" label="Poliklinik">
                        @foreach ($poli as $item)
                            @if ($item->kodedpoli == $item->kodesubspesialis)
                                <option value="{{ $item->kodedpoli }}">{{ $item->kodedpoli }} -
                                    {{ $item->namapoli }}
                                </option>
                            @endif
                        @endforeach
                        @foreach ($poli as $item)
                            @if ($item->kodedpoli != $item->kodesubspesialis)
                                <option value="{{ $item->kodesubspesialis }}">{{ $item->kodesubspesialis }} -
                                    {{ $item->namasubspesialis }}
                                </option>
                            @endif
                        @endforeach
                    </x-adminlte-select2>
                    {{-- <x-adminlte-select2 id="jadwal" name="jadwal" label="Jadwal Dokter" enable-old-support>
                    </x-adminlte-select2> --}}
                    <x-adminlte-button label="Get Jadwal" type="submit" theme="success" icon="fas fa-download" />
                </form>
            </x-adminlte-card>
        </div>
    </div>
@stop

@section('plugins.Select2', true)
@section('plugins.TempusDominusBs4', true)
@section('plugins.Datatables', true)
{{--
@section('js')
    <script>
        $(function() {
            $("#kodepoli").change(function() {
                var url = 'http://127.0.0.1:8000/api/antrian/ref/jadwal';
                // alert($("#tanggalperiksa").val());
                $.ajax({
                    url: url,
                    method: 'GET',
                    data: {
                        kodepoli: $("#kodepoli").val(),
                        tanggalperiksa: $("#tanggalperiksa").val(),
                    },
                    success: function(data) {
                        console.log(data);
                        if (data.metadata.code != 200) {
                            $("#jadwal").empty();
                            // alert(data.metadata.message);
                            return false;
                        } else {
                            $("#jadwal").empty();
                            $.each(data.response, function(item) {
                                $('#jadwal').append($('<option>', {
                                    value: data.response[item]
                                        .namasubspesialis,
                                    text: data.response[item].jadwal +
                                        ' - ' + data.response[item]
                                        .namadokter
                                }));
                            })
                        }
                    }
                });
            });
        });
    </script>
@endsection --}}
