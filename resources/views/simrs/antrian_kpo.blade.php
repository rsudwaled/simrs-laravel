@extends('adminlte::page')

@section('title', 'KPO Elektronik')

@section('content_header')
    <h1>KPO Elektronik</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-md-4">
            <x-adminlte-card title="Data Pasien" theme="secondary" collapsible>
                <x-adminlte-input name="iBasic" label="No RM" placeholder="No RM"/>
            </x-adminlte-card>
        </div>

    </div>
@stop
