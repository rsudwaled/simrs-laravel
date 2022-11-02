@extends('adminlte::page')

@section('title', 'Status Antrian TaskId')

@section('content_header')
    <h1>Status Antrian TaskId</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-md-12">
            @if ($errors->any())
                <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                    <ul>
                        @foreach ($errors->all() as $error)
                            <li>{{ $error }}</li>
                        @endforeach
                    </ul>
                </x-adminlte-alert>
            @endif
            <x-adminlte-card title="Pencarian Antrian RSUD Waled" theme="secondary" collapsible>
                <div class="row">
                    <div class="col-md-6">
                        <form action="" id="myform" method="get">
                            <x-adminlte-input name="kodebooking" label="Kode Booking" value="{{ $request->kodebooking }}"
                                placeholder="Pencarian Berdasarkan Kode Booking">
                                <x-slot name="appendSlot">
                                    <x-adminlte-button theme="success" class="withLoad" type="submit" label="Cari!" />
                                </x-slot>
                                <x-slot name="prependSlot">
                                    <div class="input-group-text text-success">
                                        <i class="fas fa-search"></i>
                                    </div>
                                </x-slot>
                            </x-adminlte-input>
                        </form>
                    </div>
                </div>
            </x-adminlte-card>
            @empty($response)
                <x-adminlte-alert title="Informasi !" theme="info" dismissable>
                    Silahkan lakukan pencarian berdasarkan Kode Booking
                </x-adminlte-alert>
            @else
                @if ($response->metadata->code != 200)
                    <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                        {{ session()->get('error') }}
                        {{ $response->metadata->message }}
                    </x-adminlte-alert>
                @else
                    <x-adminlte-card title="Pencarian Antrian RSUD Waled" theme="secondary" collapsible>
                        <div class="row">
                            <div class="col-md-12">
                                @php
                                    $heads = ['Kode Booking', 'Task Id', 'Task Name', 'Timestamp'];
                                    // $config['order'] = ['7', 'asc'];
                                @endphp
                                <x-adminlte-datatable id="table1" class="nowrap" :heads="$heads" striped bordered hoverable
                                    compressed>
                                    @foreach ($response->response as $item)
                                        <tr>
                                            <td>{{ $item->kodebooking }}</td>
                                            <td>{{ $item->taskid }}</td>
                                            <td>{{ $item->taskname }}</td>
                                            <td>{{ $item->wakturs }}</td>
                                        </tr>
                                    @endforeach
                                </x-adminlte-datatable>
                            </div>
                        </div>
                    </x-adminlte-card>
                @endif
            @endisset
        </div>
    </div>
@stop

{{-- @section('plugins.Select2', true) --}}
@section('plugins.Datatables', true)
