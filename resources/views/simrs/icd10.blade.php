@extends('adminlte::page')

@section('title', 'Referensi Tarif Layanan')

@section('content_header')
    <h1>Referensi Tarif Layanan</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <x-adminlte-card title="Data Informasi Tarif Layanan" theme="info" icon="fas fa-info-circle" collapsible
                maximizable>
                @php
                    $heads = ['Kode ICD-10', 'Name Diagnose', 'DTD'];
                    $config = [
                        'paging' => false,
                        'searching' => false,
                        'info' => false,
                    ];
                @endphp
                <form action="{{ route('icd10.index') }}" method="get">
                    <x-adminlte-input name="search" label="Pencarian ICD-10" placeholder="Pencarian ICD-10" igroup-size="sm"
                        value="{{ $request->search }}">
                        <x-slot name="appendSlot">
                            <x-adminlte-button type="submit" theme="outline-primary" label="Cari!" />
                        </x-slot>
                        <x-slot name="prependSlot">
                            <div class="input-group-text text-primary">
                                <i class="fas fa-search"></i>
                            </div>
                        </x-slot>
                    </x-adminlte-input>
                </form>
                <x-adminlte-datatable id="table1" :heads="$heads" :config="$config" striped bordered hoverable
                    compressed>
                    @foreach ($icd as $item)
                        <tr>
                            <td>{{ $item->diag }}</td>
                            <td>{{ $item->nama }}</td>
                            <td>{{ $item->dtd }}</td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
                <a href="{{ route('tarif_layanan.create') }}" class="btn btn-success">Refresh</a>
            </x-adminlte-card>
        </div>
    </div>
@stop

@section('plugins.Select2', true)
@section('plugins.Datatables', true)
